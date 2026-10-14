"""Platform helpers: OS detection, elevation, drives, protected paths, command execution."""
from __future__ import annotations

import ctypes
import json
import locale
import os
import shlex
import shutil
import subprocess
import sys
import threading
from typing import Callable, Optional

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
APP_NAME = "SysHealth"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

LogFn = Optional[Callable[[str], None]]


class NeedsAdmin(Exception):
    """Raised when an action requires administrator rights that the app does not have."""


class Cancelled(Exception):
    """Raised when the user cancels a running task."""


# --------------------------------------------------------------------------- paths
LEGACY_DATA_NAMES = ("SySentinel", "SysSentinel")  # earlier names of the app data folder, newest first
_data_root: Optional[str] = None


def _resolve_data_root() -> str:
    """Return the app data folder, moving the pre-rename folder to the new name once."""
    global _data_root
    if _data_root is not None:
        return _data_root
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    new = os.path.join(base, APP_NAME)
    _data_root = new
    if not os.path.exists(new):
        for name in LEGACY_DATA_NAMES:
            old = os.path.join(base, name)
            if os.path.isdir(old):
                try:
                    os.rename(old, new)
                except OSError:
                    _data_root = old  # in use or not permitted: keep using the existing folder
                break
    return _data_root


def app_data_dir(*sub: str) -> str:
    path = os.path.join(_resolve_data_root(), *sub)
    os.makedirs(path, exist_ok=True)
    return path


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def protected_roots() -> list[str]:
    """Locations whose files must never be deleted by duplicate cleanup."""
    if IS_WINDOWS:
        roots = [
            os.environ.get("SystemRoot", r"C:\Windows"),
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("ProgramW6432", r"C:\Program Files"),
            os.environ.get("ProgramData", r"C:\ProgramData"),
        ]
        drive = os.environ.get("SystemDrive", "C:") + "\\"
        for name in ("$Recycle.Bin", "System Volume Information", "Recovery",
                     "$WinREAgent", "Config.Msi", "Boot", "EFI"):
            roots.append(os.path.join(drive, name))
    else:
        roots = ["/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
                 "/opt", "/proc", "/root", "/run", "/sbin", "/snap", "/srv", "/sys",
                 "/usr", "/var", "/lost+found"]
    return sorted({norm(r) for r in roots if r})


def is_protected(path: str) -> bool:
    p = norm(path)
    for root in protected_roots():
        if p == root or p.startswith(root + os.sep):
            return True
    return False


# --------------------------------------------------------------------------- elevation
def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def relaunch_as_admin(extra_args: Optional[list[str]] = None) -> bool:
    """Windows only: restart this program with a UAC prompt. Returns True if launched."""
    if not IS_WINDOWS:
        return False
    passthrough = [a for a in sys.argv[1:] if a not in (extra_args or [])] + (extra_args or [])
    if getattr(sys, "frozen", False):
        exe, args = sys.executable, passthrough
    else:
        exe, args = sys.executable, [os.path.abspath(sys.argv[0])] + passthrough
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, subprocess.list2cmdline(args), None, 1)
    return rc > 32


def wrap_privileged(cmds: list[list[str]]) -> list[str]:
    """Linux: run one or more commands through a single pkexec (one password prompt)."""
    if len(cmds) == 1:
        return ["pkexec"] + cmds[0]
    return ["pkexec", "sh", "-c", " && ".join(shlex.join(c) for c in cmds)]


# --------------------------------------------------------------------------- drives
def list_drives() -> list[str]:
    import psutil
    out: list[str] = []
    for p in psutil.disk_partitions(all=False):
        if IS_WINDOWS:
            if "cdrom" in p.opts or not p.fstype:
                continue
        else:
            if p.fstype in ("squashfs", "tmpfs", "devtmpfs", "overlay"):
                continue
            if p.mountpoint.startswith(("/snap", "/boot", "/var/snap", "/run")):
                continue
        if p.mountpoint not in out:
            out.append(p.mountpoint)
    return out


def windows_drive_letters() -> list[str]:
    return [d[0].upper() for d in list_drives() if len(d) >= 2 and d[1] == ":"]


def win_system_exe(name: str) -> str:
    """Path to a System32 tool, bypassing WOW64 redirection for 32-bit Python."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    sysnative = os.path.join(root, "Sysnative")
    if os.path.isdir(sysnative):
        return os.path.join(sysnative, name)
    return os.path.join(root, "System32", name)


# --------------------------------------------------------------------------- decoding
def _oem_encoding() -> str:
    if IS_WINDOWS:
        try:
            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            pass
    return locale.getpreferredencoding(False) or "utf-8"


def decode_bytes(data: bytes) -> str:
    if not data:
        return ""
    # Tools such as sfc.exe write UTF-16; stripping NULs recovers readable ASCII text.
    if data.count(b"\x00") > len(data) // 4:
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            data = data.replace(b"\x00", b"")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode(_oem_encoding(), errors="replace")


# --------------------------------------------------------------------------- commands
def run_cmd(cmd: list[str], timeout: Optional[float] = 120, stdin_text: Optional[str] = None) -> tuple[int, str]:
    try:
        cp = subprocess.run(cmd, input=stdin_text.encode() if stdin_text else None,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=None if stdin_text else subprocess.DEVNULL,
                            timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"Command timed out: {' '.join(cmd)}"
    return cp.returncode, decode_bytes(cp.stdout)


def run_stream(cmd: list[str], on_line: LogFn = None, cancel: Optional[threading.Event] = None,
               stdin_text: Optional[str] = None) -> tuple[int, str]:
    """Run a command, forwarding each output line to on_line. Supports cancellation."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.PIPE if stdin_text else subprocess.DEVNULL,
                                creationflags=CREATE_NO_WINDOW)
    except FileNotFoundError:
        raise RuntimeError(f"Command not found: {cmd[0]}")
    if stdin_text:
        try:
            proc.stdin.write(stdin_text.encode())
            proc.stdin.close()
        except OSError:
            pass

    if cancel is not None:
        def _watch():
            while proc.poll() is None:
                if cancel.wait(0.5):
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    return
        threading.Thread(target=_watch, daemon=True).start()

    lines: list[str] = []
    for raw in iter(proc.stdout.readline, b""):
        text = decode_bytes(raw.replace(b"\x00", b"")).rstrip("\r\n")
        if "\r" in text:  # progress counters overwrite the same line
            text = text.split("\r")[-1]
        text = text.strip()
        if text:
            lines.append(text)
            if on_line:
                on_line(text)
    rc = proc.wait()
    if cancel is not None and cancel.is_set():
        raise Cancelled()
    return rc, "\n".join(lines)


def powershell(script: str, timeout: Optional[float] = 180) -> tuple[int, str]:
    prefix = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; "
    return run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-Command", prefix + script], timeout=timeout)


def ps_json(script: str, timeout: Optional[float] = 180) -> list[dict]:
    rc, out = powershell(f"{script} | ConvertTo-Json -Depth 4 -Compress", timeout)
    out = out.strip()
    if not out:
        return []
    start = min([i for i in (out.find("["), out.find("{")) if i >= 0], default=-1)
    if start < 0:
        return []
    try:
        data = _unwrap_ps(json.loads(out[start:]))
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def _unwrap_ps(obj):
    """Windows PowerShell 5.1 serializes strings that carry provider metadata (for example lines read with
    Get-Content) as {"value": "...", "PSPath": ...}. Turn those back into plain strings."""
    if isinstance(obj, dict):
        if "value" in obj and any(k.startswith("PS") for k in obj):
            return _unwrap_ps(obj["value"])
        return {k: _unwrap_ps(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_unwrap_ps(v) for v in obj]
    return obj


def open_location(path: str) -> None:
    """Show a file in the system file manager."""
    if IS_WINDOWS:
        if os.path.isfile(path):
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        else:
            os.startfile(path if os.path.isdir(path) else os.path.dirname(path))  # type: ignore[attr-defined]
    else:
        target = path if os.path.isdir(path) else os.path.dirname(path)
        opener = shutil.which("xdg-open") or "xdg-open"
        subprocess.Popen([opener, target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def open_url_or_file(target: str) -> None:
    if IS_WINDOWS:
        os.startfile(target)  # type: ignore[attr-defined]
    else:
        subprocess.Popen([shutil.which("xdg-open") or "xdg-open", target],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
