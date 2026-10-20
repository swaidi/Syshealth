"""Small Linux helper tools that make SysHealth work fully. Offered once on first start, installable any time.

- Clipboard tool (xclip, or wl-clipboard on Wayland): copied text stays available after SysHealth closes.
- smartmontools (smartctl): disk health readings on the Disk Health page.
"""
from __future__ import annotations

import os
import shutil
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from .platform_utils import IS_LINUX, is_admin, run_stream, wrap_privileged

LogFn = Optional[Callable[[str], None]]


@dataclass
class Tool:
    command: str
    package: str
    purpose: str


def wanted() -> list[Tool]:
    clip = (Tool("wl-copy", "wl-clipboard", "copying text reliably") if os.environ.get("WAYLAND_DISPLAY")
            else Tool("xclip", "xclip", "copying text reliably"))
    return [clip, Tool("smartctl", "smartmontools", "disk health readings")]


def missing() -> list[Tool]:
    if not IS_LINUX:
        return []
    found = lambda cmd: shutil.which(cmd) or os.path.exists(f"/usr/sbin/{cmd}") or os.path.exists(f"/sbin/{cmd}")
    return [t for t in wanted() if not found(t.command)]


def install_commands(packages: list[str]) -> list[list[str]]:
    if shutil.which("apt-get"):
        return [["apt-get", "install", "-y", *packages]]
    if shutil.which("dnf"):
        return [["dnf", "install", "-y", *packages]]
    if shutil.which("zypper"):
        return [["zypper", "--non-interactive", "install", *packages]]
    if shutil.which("pacman"):
        return [["pacman", "-S", "--noconfirm", "--needed", *packages]]
    raise RuntimeError("No supported package manager found (apt, dnf, zypper, pacman). Install these packages "
                       "with your distribution's software manager: " + ", ".join(packages))


def install(tools: list[Tool], log: LogFn, cancel: Optional[threading.Event]) -> None:
    packages = [t.package for t in tools]
    cmds = install_commands(packages)
    if log:
        log(f"Installing {', '.join(packages)} (you will be asked for your password)…")
    if is_admin():
        rc = 0
        for c in cmds:
            rc, _ = run_stream(c, log, cancel)
            if rc != 0:
                break
    else:
        rc, _ = run_stream(wrap_privileged(cmds), log, cancel)
    if rc != 0:
        raise RuntimeError(f"Installation did not complete (exit code {rc}). If the password window was "
                           "cancelled, you can install later with: SysHealthCLI linux-tools install")
