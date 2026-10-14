"""Shared structures for health checks and repair actions."""
from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from .platform_utils import IS_WINDOWS, NeedsAdmin, is_admin, run_stream, wrap_privileged

LogFn = Optional[Callable[[str], None]]

OK, WARN, FAIL, INFO = "OK", "WARN", "FAIL", "INFO"


@dataclass
class Check:
    name: str
    status: str
    detail: str
    fix_id: Optional[str] = None


@dataclass
class Fix:
    id: str
    title: str
    description: str
    commands: list[list[str]] = field(default_factory=list)
    admin: bool = False
    reboot: bool = False
    stdin: Optional[str] = None
    python_fn: Optional[Callable[[LogFn, Optional[threading.Event]], None]] = None

    def preview(self) -> str:
        if self.python_fn:
            return "(built-in action)"
        return "\n".join(subprocess.list2cmdline(c) for c in self.commands)


def execute_fix(fix: Fix, log: LogFn, cancel: Optional[threading.Event]) -> None:
    if fix.python_fn:
        fix.python_fn(log, cancel)
        return
    elevated = is_admin()
    if IS_WINDOWS:
        if fix.admin and not elevated:
            raise NeedsAdmin(fix.title)
        for cmd in fix.commands:
            if log:
                log(f"> {subprocess.list2cmdline(cmd)}")
            rc, _ = run_stream(cmd, log, cancel, stdin_text=fix.stdin)
            if log:
                log(f"Exit code: {rc}")
        return
    if fix.admin and not elevated:
        cmd = wrap_privileged(fix.commands)
        if log:
            log(f"> {' '.join(cmd)}  (you will be asked for your password)")
        rc, _ = run_stream(cmd, log, cancel, stdin_text=fix.stdin)
        if log:
            log(f"Exit code: {rc}")
        return
    for cmd in fix.commands:
        if log:
            log(f"> {' '.join(cmd)}")
        rc, _ = run_stream(cmd, log, cancel, stdin_text=fix.stdin)
        if log:
            log(f"Exit code: {rc}")
