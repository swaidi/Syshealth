"""Application updates: winget on Windows; apt, dnf and flatpak on Linux."""
from __future__ import annotations

import re
import shutil
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from .platform_utils import IS_WINDOWS, is_admin, run_cmd, run_stream, wrap_privileged

LogFn = Optional[Callable[[str], None]]
WINGET_FLAGS = ["--accept-source-agreements", "--disable-interactivity"]


@dataclass
class UpdateItem:
    name: str
    id: str
    current: str
    available: str
    source: str


def manager_name() -> str:
    if IS_WINDOWS:
        return "winget" if shutil.which("winget") else ""
    for m in ("apt", "dnf", "flatpak"):
        if shutil.which("apt-get" if m == "apt" else m):
            return m
    return ""


# --------------------------------------------------------------------------- winget
def parse_winget_table(text: str) -> list[UpdateItem]:
    """Parse winget's upgrade table. Columns are read from the right (Source, Available, Version, Id never
    contain spaces), so overflowing names and localized headers do not break parsing."""
    lines = [l.split("\r")[-1].rstrip() for l in text.splitlines()]
    sep = next((i for i, l in enumerate(lines) if re.fullmatch(r"-{10,}", l.strip())), None)
    if sep is None:
        return []
    items = []
    for line in lines[sep + 1:]:
        tokens = line.split()
        if not tokens:
            break  # a blank line ends the first table
        if len(tokens) < 5:
            if re.match(r"^\d+\s", line.strip()):
                break  # "N upgrades available." footer
            continue
        source, available, version = tokens[-1], tokens[-2], tokens[-3]
        idx = -4
        if tokens[idx] in ("<", ">") and len(tokens) >= 6:
            version = f"{tokens[idx]} {version}"
            idx -= 1
        name = " ".join(tokens[:idx]).rstrip("…").strip()
        items.append(UpdateItem(name or tokens[idx], tokens[idx], version, available, source))
    return items


def _winget_list() -> list[UpdateItem]:
    rc, out = run_cmd(["winget", "upgrade", "--include-unknown"] + WINGET_FLAGS, timeout=300)
    return parse_winget_table(out)


# --------------------------------------------------------------------------- Linux
def _apt_list() -> list[UpdateItem]:
    rc, out = run_cmd(["apt", "list", "--upgradable"], timeout=120)
    items = []
    for line in out.splitlines():
        m = re.match(r"^(\S+?)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", line)
        if m:
            items.append(UpdateItem(m.group(1), m.group(1), m.group(3), m.group(2), "apt"))
    return items


def _dnf_list() -> list[UpdateItem]:
    rc, out = run_cmd(["dnf", "check-update", "-q"], timeout=300)
    items = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and "." in parts[0]:
            items.append(UpdateItem(parts[0], parts[0], "", parts[1], parts[2]))
    return items


def _flatpak_list() -> list[UpdateItem]:
    if not shutil.which("flatpak"):
        return []
    rc, out = run_cmd(["flatpak", "remote-ls", "--updates", "--columns=name,application,version"], timeout=120)
    items = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            items.append(UpdateItem(parts[0], parts[1], "", parts[2] if len(parts) > 2 else "", "flatpak"))
    return items


# --------------------------------------------------------------------------- public API
def list_updates(log: LogFn = None) -> list[UpdateItem]:
    if IS_WINDOWS:
        if not shutil.which("winget"):
            raise RuntimeError("winget (App Installer) is not available. Install 'App Installer' from the "
                               "Microsoft Store.")
        return _winget_list()
    items: list[UpdateItem] = []
    if shutil.which("apt"):
        items += _apt_list()
    elif shutil.which("dnf"):
        items += _dnf_list()
    items += _flatpak_list()
    return items


def refresh_sources(log: LogFn, cancel: Optional[threading.Event]) -> None:
    if IS_WINDOWS:
        run_stream(["winget", "source", "update"], log, cancel)
    elif shutil.which("apt-get"):
        cmd = ["apt-get", "update"]
        run_stream(cmd if is_admin() else wrap_privileged([cmd]), log, cancel)


def install(items: list[UpdateItem], log: LogFn, cancel: Optional[threading.Event]) -> tuple[int, list[str]]:
    """Update the given items. Returns (succeeded, failures)."""
    ok, failed = 0, []
    if IS_WINDOWS:
        for it in items:
            if log:
                log(f"Updating {it.name} ({it.current} → {it.available})…")
            rc, _ = run_stream(["winget", "upgrade", "--id", it.id, "--exact", "--silent",
                                "--accept-package-agreements"] + WINGET_FLAGS, log, cancel)
            if rc == 0:
                ok += 1
            else:
                failed.append(f"{it.name}: exit code {rc}")
        return ok, failed
    native = [it for it in items if it.source != "flatpak"]
    flat = [it for it in items if it.source == "flatpak"]
    if native:
        if shutil.which("apt-get"):
            cmd = ["apt-get", "install", "--only-upgrade", "-y"] + [it.id for it in native]
        else:
            cmd = ["dnf", "upgrade", "-y"] + [it.id for it in native]
        rc, _ = run_stream(cmd if is_admin() else wrap_privileged([cmd]), log, cancel)
        if rc == 0:
            ok += len(native)
        else:
            failed.append(f"Package manager exit code {rc}")
    for it in flat:
        rc, _ = run_stream(["flatpak", "update", "-y", it.id], log, cancel)
        if rc == 0:
            ok += 1
        else:
            failed.append(f"{it.name}: exit code {rc}")
    return ok, failed


def install_all(log: LogFn, cancel: Optional[threading.Event]) -> int:
    if IS_WINDOWS:
        rc, _ = run_stream(["winget", "upgrade", "--all", "--silent", "--accept-package-agreements"] + WINGET_FLAGS,
                           log, cancel)
        return rc
    if shutil.which("apt-get"):
        cmds = [["apt-get", "update"], ["apt-get", "upgrade", "-y"]]
    else:
        cmds = [["dnf", "upgrade", "-y"]]
    if is_admin():
        rc = 0
        for c in cmds:
            rc, _ = run_stream(c, log, cancel)
    else:
        rc, _ = run_stream(wrap_privileged(cmds), log, cancel)
    if shutil.which("flatpak"):
        run_stream(["flatpak", "update", "-y"], log, cancel)
    return rc
