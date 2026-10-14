"""Secure deletion: overwrite file contents before removing them.

Note: on SSDs, flash drives and cloud-synced folders, overwriting cannot guarantee that every physical
copy is destroyed (wear levelling, snapshots, sync history). Full-disk encryption is the reliable
protection there.
"""
from __future__ import annotations

import os
import stat
import threading
import uuid
from typing import Callable, Optional

from .platform_utils import Cancelled, is_protected

LogFn = Optional[Callable[[str], None]]
CHUNK = 1024 * 1024


def _overwrite(path: str, passes: int, cancel: Optional[threading.Event]) -> int:
    size = os.path.getsize(path)
    with open(path, "r+b", buffering=0) as fh:
        for n in range(passes):
            fh.seek(0)
            remaining = size
            while remaining > 0:
                if cancel is not None and cancel.is_set():
                    raise Cancelled()
                block = min(CHUNK, remaining)
                fh.write(os.urandom(block) if n < passes - 1 or passes == 1 else b"\x00" * block)
                remaining -= block
            fh.flush()
            os.fsync(fh.fileno())
        fh.truncate(0)
        os.fsync(fh.fileno())
    return size


def shred_file(path: str, passes: int = 1, cancel: Optional[threading.Event] = None) -> int:
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    size = _overwrite(path, passes, cancel)
    anon = os.path.join(os.path.dirname(path), uuid.uuid4().hex[:12])
    os.rename(path, anon)  # hide the original name
    os.remove(anon)
    return size


def check_allowed(path: str) -> Optional[str]:
    p = os.path.abspath(path)
    if is_protected(p):
        return "is inside a protected system folder"
    if os.path.dirname(p) == p or (len(p) <= 3 and p[1:2] == ":"):
        return "is a drive root"
    if p in (os.path.expanduser("~"), os.path.abspath(os.sep)):
        return "is your home folder"
    return None


def shred(paths: list[str], passes: int, log: LogFn, cancel: Optional[threading.Event]) -> tuple[int, int, list[str]]:
    """Shred files and folders. Returns (files shredded, bytes, errors)."""
    count, total, errors = 0, 0, []
    for target in paths:
        reason = check_allowed(target)
        if reason:
            errors.append(f"{target}: skipped because it {reason}")
            continue
        if os.path.isfile(target) and not os.path.islink(target):
            files, dirs = [target], []
        else:
            files, dirs = [], []
            for dp, dn, fn in os.walk(target, topdown=False):
                files += [os.path.join(dp, f) for f in fn if not os.path.islink(os.path.join(dp, f))]
                dirs.append(dp)
        for f in files:
            try:
                total += shred_file(f, passes, cancel)
                count += 1
                if log:
                    log(f"Shredded: {f}")
            except Cancelled:
                raise
            except OSError as exc:
                errors.append(f"{f}: {exc}")
        for d in dirs:
            try:
                os.rmdir(d)
            except OSError:
                pass
    return count, total, errors
