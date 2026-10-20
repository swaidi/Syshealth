"""Autostart (persistence) inventory: everything that starts automatically, with signature status,
risk flags, enable/disable support and change tracking between scans."""
from __future__ import annotations

import configparser
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import threading
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

from .platform_utils import (IS_WINDOWS, Cancelled, NeedsAdmin, app_data_dir, is_admin, norm, ps_json, run_cmd,
                             wrap_privileged)

LogFn = Optional[Callable[[str], None]]

# categories shown on the simple Startup Apps page
STARTUP_CATEGORIES = {"Run key", "Startup folder", "Autostart"}
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "rundll32.exe",
                "regsvr32.exe", "cmd.exe"}


@dataclass
class AutoEntry:
    category: str           # Run key | Startup folder | Service | Scheduled task | Browser extension | ...
    name: str
    command: str
    location: str           # where it is registered
    enabled: bool = True
    scope: str = "user"     # user | machine
    path: str = ""          # resolved executable or file
    signer: str = ""
    sig_status: str = ""    # Valid | NotSigned | ... | Missing | n/a
    flags: list[str] = field(default_factory=list)
    can_toggle: bool = False
    meta: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return hashlib.sha1(f"{self.category}|{self.location}|{self.name}|{self.command}".encode()).hexdigest()

    @property
    def risk(self) -> str:
        if any(f in self.flags for f in ("File missing", "IFEO debugger", "Unusual Winlogon value", "WMI consumer")):
            return "High"
        if self.flags:
            return "Review"
        return "Low"


# =========================================================================== helpers
def extract_path(command: str) -> str:
    """Best-effort extraction of the executable from a command line."""
    cmd = os.path.expandvars(command.strip())
    if not cmd:
        return ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd.strip('"')
    if IS_WINDOWS:
        parts = cmd.split(" ")
        for i in range(len(parts), 0, -1):  # handle unquoted paths with spaces
            cand = " ".join(parts[:i])
            if os.path.isfile(cand):
                return cand
        first = parts[0]
        if first.lower().startswith("\\??\\"):
            first = first[4:]
        found = shutil.which(first)
        if found:
            return found
        sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", first)
        return sysdir if os.path.isfile(sysdir) else first
    try:
        first = shlex.split(cmd)[0]
    except ValueError:
        first = cmd.split()[0]
    if first == "env":  # e.g. "env FOO=1 /usr/bin/app"
        rest = [t for t in shlex.split(cmd)[1:] if "=" not in t]
        first = rest[0] if rest else first
    return shutil.which(first) or first


def _user_writable(path: str) -> bool:
    p = norm(path)
    if IS_WINDOWS:
        risky = [os.environ.get("TEMP", ""), os.environ.get("APPDATA", ""), os.path.expanduser("~\\Downloads"),
                 os.environ.get("PUBLIC", r"C:\Users\Public"), os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp")]
    else:
        risky = ["/tmp", "/var/tmp", "/dev/shm", os.path.expanduser("~/Downloads")]
    return any(r and (p == norm(r) or p.startswith(norm(r) + os.sep)) for r in risky)


def _flag(entry: AutoEntry) -> None:
    exe = os.path.basename(entry.path).lower()
    if entry.path and entry.category not in ("Browser extension",) and not os.path.exists(entry.path) \
            and os.sep in entry.path:
        entry.flags.append("File missing")
    if entry.path and _user_writable(entry.path):
        entry.flags.append("User-writable location")
    if exe in SCRIPT_HOSTS and entry.category != "Service":
        entry.flags.append("Script launcher")
    if entry.sig_status and entry.sig_status not in ("Valid", "n/a", "Missing", ""):
        entry.flags.append("Unsigned" if entry.sig_status == "NotSigned" else f"Signature: {entry.sig_status}")


# =========================================================================== Windows collectors
def _win_startup_approved(hive, sub: str, value_name: str) -> Optional[bool]:
    import winreg
    try:
        with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" + "\\" + sub) as k:
            data = winreg.QueryValueEx(k, value_name)[0]
            return not (bytes(data)[0] & 1)  # 02 = enabled, 03 = disabled
    except OSError:
        return None


def _win_run_keys() -> list[AutoEntry]:
    import winreg
    out = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "user", "Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "user", None),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "machine", "Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "machine", None),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "machine", "Run32"),
    ]
    for hive, path, scope, approved in keys:
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    state = _win_startup_approved(hive, approved, name) if approved else None
                    hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                    out.append(AutoEntry("Run key", name, str(value), f"{hive_name}\\{path}",
                                         enabled=state is not False, scope=scope, path=extract_path(str(value)),
                                         can_toggle=approved is not None,
                                         meta={"hive": hive_name, "approved": approved or ""}))
        except OSError:
            continue
    return out


def _win_startup_folders() -> list[AutoEntry]:
    import winreg
    out, links = [], []
    folders = [(os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
                "user", winreg.HKEY_CURRENT_USER),
               (os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                             r"Microsoft\Windows\Start Menu\Programs\StartUp"), "machine", winreg.HKEY_LOCAL_MACHINE)]
    for folder, scope, hive in folders:
        if not os.path.isdir(folder):
            continue
        for name in os.listdir(folder):
            if name.lower() == "desktop.ini":
                continue
            full = os.path.join(folder, name)
            state = _win_startup_approved(hive, "StartupFolder", name)
            e = AutoEntry("Startup folder", os.path.splitext(name)[0], full, folder, enabled=state is not False,
                          scope=scope, path=full, can_toggle=True,
                          meta={"hive": "HKCU" if scope == "user" else "HKLM", "approved": "StartupFolder",
                                "value": name})
            out.append(e)
            if name.lower().endswith(".lnk"):
                links.append(e)
    if links:  # resolve shortcut targets in one PowerShell call
        script = ("$s = New-Object -ComObject WScript.Shell; @(" +
                  ",".join("'" + e.path.replace("'", "''") + "'" for e in links) +
                  ") | ForEach-Object { [pscustomobject]@{L=$_; T=$s.CreateShortcut($_).TargetPath; "
                  "A=$s.CreateShortcut($_).Arguments} }")
        targets = {r.get("L"): (r.get("T") or "", r.get("A") or "") for r in ps_json(script)}
        for e in links:
            t, a = targets.get(e.path, ("", ""))
            if t:
                e.path, e.command = t, f'"{t}" {a}'.strip()
    return out


def _win_services() -> list[AutoEntry]:
    rows = ps_json("Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -or $_.StartMode -eq "
                   "'Disabled' } | Select-Object Name, DisplayName, PathName, StartMode, State")
    out = []
    for r in rows:
        cmd = r.get("PathName") or ""
        out.append(AutoEntry("Service", r.get("DisplayName") or r.get("Name", ""), cmd, "Services",
                             enabled=r.get("StartMode") != "Disabled", scope="machine", path=extract_path(cmd),
                             can_toggle=True, meta={"service": r.get("Name", ""), "state": r.get("State", "")}))
    return out


def _win_tasks() -> list[AutoEntry]:
    rows = ps_json("Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | ForEach-Object { "
                   "$a = $_.Actions | Where-Object { $_.Execute } | Select-Object -First 1; "
                   "[pscustomobject]@{N=$_.TaskName; P=$_.TaskPath; S=\"$($_.State)\"; E=$a.Execute; A=$a.Arguments} }")
    out = []
    for r in rows:
        exe = r.get("E") or ""
        cmd = f'"{exe}" {r.get("A") or ""}'.strip() if exe else "(COM handler)"
        out.append(AutoEntry("Scheduled task", r.get("N", ""), cmd, f"Task Scheduler {r.get('P', '')}",
                             enabled=r.get("S") != "Disabled", scope="machine",
                             path=extract_path(os.path.expandvars(exe)) if exe else "", can_toggle=True,
                             meta={"task": r.get("N", ""), "task_path": r.get("P", "\\")}))
    return out


def _win_special() -> list[AutoEntry]:
    import winreg
    out = []
    expected = {"Shell": "explorer.exe", "Userinit": "userinit.exe"}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") as k:
            for value, ok in expected.items():
                try:
                    data = str(winreg.QueryValueEx(k, value)[0])
                except OSError:
                    continue
                parts = [p.strip().strip(",") for p in data.split(",") if p.strip().strip(",")]
                e = AutoEntry("Winlogon", value, data, r"HKLM\...\Winlogon", scope="machine",
                              path=extract_path(parts[0]) if parts else "")
                if len(parts) != 1 or not parts[0].lower().endswith(ok):
                    e.flags.append("Unusual Winlogon value")
                out.append(e)
    except OSError:
        pass
    try:
        base = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(k, sub) as sk:
                        dbg = str(winreg.QueryValueEx(sk, "Debugger")[0])
                        e = AutoEntry("IFEO debugger", sub, dbg, r"HKLM\...\Image File Execution Options",
                                      scope="machine", path=extract_path(dbg))
                        e.flags.append("IFEO debugger")
                        out.append(e)
                except OSError:
                    continue
    except OSError:
        pass
    for r in ps_json("Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer -ErrorAction "
                     "SilentlyContinue | Select-Object Name, CommandLineTemplate, ScriptText"):
        if r.get("Name") == "SCM Event Log Consumer":
            continue
        cmd = r.get("CommandLineTemplate") or (r.get("ScriptText") or "")[:200]
        e = AutoEntry("WMI consumer", r.get("Name", ""), cmd, r"WMI root\subscription", scope="machine",
                      path=extract_path(cmd) if r.get("CommandLineTemplate") else "")
        e.flags.append("WMI consumer")
        out.append(e)
    return out


# =========================================================================== browser extensions
def _chromium_profiles() -> list[tuple[str, str]]:
    if IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA", "")
        bases = {"Chrome": os.path.join(local, r"Google\Chrome\User Data"),
                 "Edge": os.path.join(local, r"Microsoft\Edge\User Data"),
                 "Brave": os.path.join(local, r"BraveSoftware\Brave-Browser\User Data")}
    else:
        home = os.path.expanduser("~")
        bases = {"Chrome": os.path.join(home, ".config", "google-chrome"),
                 "Chromium": os.path.join(home, ".config", "chromium"),
                 "Brave": os.path.join(home, ".config", "BraveSoftware", "Brave-Browser"),
                 "Edge": os.path.join(home, ".config", "microsoft-edge")}
    out = []
    for browser, base in bases.items():
        for prof in glob.glob(os.path.join(base, "*", "Extensions")):
            out.append((browser, prof))
    return out


def _ext_name(manifest_dir: str, manifest: dict) -> str:
    name = manifest.get("name", "")
    m = re.match(r"__MSG_(.+)__", name)
    if m:
        for loc in (manifest.get("default_locale", "en"), "en", "en_US"):
            try:
                with open(os.path.join(manifest_dir, "_locales", loc, "messages.json"), encoding="utf-8") as fh:
                    msgs = json.load(fh)
                for k, v in msgs.items():
                    if k.lower() == m.group(1).lower():
                        return v.get("message", name)
            except (OSError, json.JSONDecodeError):
                continue
    return name


def _browser_extensions() -> list[AutoEntry]:
    out = []
    for browser, ext_dir in _chromium_profiles():
        profile = os.path.basename(os.path.dirname(ext_dir))
        for ext_id in os.listdir(ext_dir):
            versions = sorted(glob.glob(os.path.join(ext_dir, ext_id, "*", "manifest.json")))
            if not versions:
                continue
            mdir = os.path.dirname(versions[-1])
            try:
                with open(versions[-1], encoding="utf-8-sig") as fh:
                    manifest = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            name = _ext_name(mdir, manifest) or ext_id
            perms = manifest.get("permissions", []) + manifest.get("host_permissions", [])
            e = AutoEntry("Browser extension", name, f"{browser} ({profile}) · id {ext_id}", f"{browser} {profile}",
                          scope="user", path=mdir, sig_status="n/a",
                          meta={"browser": browser, "permissions": [str(p) for p in perms][:30]})
            if any(p in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*") for p in map(str, perms)):
                e.flags.append("Can read all websites")
            out.append(e)
    profiles = (glob.glob(os.path.join(os.environ.get("APPDATA", ""), r"Mozilla\Firefox\Profiles\*")) if IS_WINDOWS
                else glob.glob(os.path.expanduser("~/.mozilla/firefox/*")))
    for prof in profiles:
        try:
            with open(os.path.join(prof, "extensions.json"), encoding="utf-8") as fh:
                addons = json.load(fh).get("addons", [])
        except (OSError, json.JSONDecodeError):
            continue
        for a in addons:
            if a.get("location") != "app-profile" or a.get("type") != "extension":
                continue
            name = (a.get("defaultLocale") or {}).get("name") or a.get("id", "")
            out.append(AutoEntry("Browser extension", name, f"Firefox · id {a.get('id')}", "Firefox",
                                 enabled=bool(a.get("active")), scope="user", path=prof, sig_status="n/a",
                                 meta={"browser": "Firefox"}))
    return out


# =========================================================================== Linux collectors
def _linux_autostart() -> list[AutoEntry]:
    out = []
    user_dir = os.path.expanduser("~/.config/autostart")
    seen = set()
    for folder, scope in ((user_dir, "user"), ("/etc/xdg/autostart", "machine")):
        for f in sorted(glob.glob(os.path.join(folder, "*.desktop"))):
            name = os.path.basename(f)
            if scope == "machine" and name in seen:
                continue  # overridden by the user copy
            seen.add(name)
            cp = configparser.ConfigParser(interpolation=None, strict=False)
            try:
                cp.read(f, encoding="utf-8")
                sec = cp["Desktop Entry"]
            except (configparser.Error, KeyError, UnicodeDecodeError):
                continue
            hidden = sec.get("Hidden", "false").lower() == "true"
            gnome_off = sec.get("X-GNOME-Autostart-enabled", "true").lower() == "false"
            cmd = sec.get("Exec", "")
            out.append(AutoEntry("Autostart", sec.get("Name", name), cmd, folder, enabled=not (hidden or gnome_off),
                                 scope=scope, path=extract_path(cmd), sig_status="n/a", can_toggle=True,
                                 meta={"file": name}))
    return out


def _linux_systemd() -> list[AutoEntry]:
    out = []
    if not shutil.which("systemctl"):
        return out
    for user in (True, False):
        base = ["systemctl", "--user"] if user else ["systemctl"]
        rc, text = run_cmd(base + ["list-unit-files", "--type=service", "--state=enabled,disabled",
                                   "--no-legend", "--no-pager"])
        if rc != 0:
            continue
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 2 or parts[1] not in ("enabled", "disabled") or "@" in parts[0]:
                continue
            unit = parts[0]
            rc2, exec_out = run_cmd(base + ["show", "-p", "ExecStart", "--value", unit], timeout=10)
            if rc2 != 0:
                exec_out = ""
            m = re.search(r"path=(\S+)", exec_out)
            path = m.group(1) if m else ""
            # keep only the command line: the rest (start_time, pid, status) changes at every boot
            argv = re.search(r"argv\[\]=([^;]*)", exec_out)
            command = (argv.group(1).strip() if argv else path) or unit
            if not user and path.startswith(("/usr/", "/lib/", "/bin/", "/sbin/")) and parts[1] == "enabled":
                # distribution-provided service; keep but it is low interest
                pass
            out.append(AutoEntry("Service", unit, command[:300],
                                 "systemd (user)" if user else "systemd (system)", enabled=parts[1] == "enabled",
                                 scope="user" if user else "machine", path=path, sig_status="n/a",
                                 can_toggle=True, meta={"unit": unit, "user": user}))
    return out


def _linux_cron() -> list[AutoEntry]:
    out = []
    rc, text = run_cmd(["crontab", "-l"])
    sources = [("crontab (user)", text if rc == 0 else "")]
    for f in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                sources.append((f, fh.read()))
        except OSError:
            continue
    for where, content in sources:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or re.match(r"^[A-Z_]+=", line):
                continue
            fields = line.split()
            cmd_fields = fields[1:] if line.startswith("@") else fields[5:]
            if where != "crontab (user)" and not line.startswith("@") and len(fields) > 6:
                cmd_fields = fields[6:]  # system crontabs include a user column
            cmd = " ".join(cmd_fields)
            if not cmd:
                continue
            e = AutoEntry("Scheduled task", cmd[:60], cmd, where, scope="user" if "user" in where else "machine",
                          path=extract_path(cmd), sig_status="n/a")
            if re.search(r"(curl|wget)\s.*\|\s*(ba)?sh|base64\s+-d|\bnc\b.*-e", cmd):
                e.flags.append("Downloads and runs code")
            out.append(e)
    return out


def _linux_shell_rc() -> list[AutoEntry]:
    out = []
    for f in ("~/.bashrc", "~/.profile", "~/.bash_profile", "~/.zshrc"):
        path = os.path.expanduser(f)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    if re.search(r"(curl|wget)\s.*\|\s*(ba)?sh|base64\s+-d|\bnc\b.*-e|/dev/tcp/", line):
                        e = AutoEntry("Shell startup", f"{os.path.basename(path)}:{n}", line.strip(), path,
                                      path=path, sig_status="n/a")
                        e.flags.append("Downloads and runs code")
                        out.append(e)
        except OSError:
            continue
    return out


# =========================================================================== public API
def collect(categories: Optional[set[str]] = None, signatures: bool = True, log: LogFn = None,
            cancel: Optional[threading.Event] = None) -> list[AutoEntry]:
    want = (lambda c: categories is None or c in categories)
    entries: list[AutoEntry] = []

    def read(label: str, fn) -> None:
        """Read one autostart source; a failure is logged and the remaining sources are still read."""
        if log:
            log(f"Reading {label}…")
        try:
            entries.extend(fn())
        except Exception as exc:  # noqa: BLE001 - one source must not stop the scan
            if log:
                log(f"Could not read {label}: {type(exc).__name__}: {exc}")

    if IS_WINDOWS:
        if want("Run key"):
            read("registry Run keys", _win_run_keys)
        if want("Startup folder"):
            read("startup folders", _win_startup_folders)
        if want("Service"):
            read("services", _win_services)
        if want("Scheduled task"):
            read("scheduled tasks", _win_tasks)
        if categories is None:
            read("Winlogon, IFEO and WMI entries", _win_special)
    else:
        if want("Autostart"):
            read("autostart entries", _linux_autostart)
        if want("Service"):
            read("systemd services", _linux_systemd)
        if want("Scheduled task"):
            read("cron jobs", _linux_cron)
        if categories is None:
            read("shell startup files", _linux_shell_rc)
    if want("Browser extension"):
        read("browser extensions", _browser_extensions)

    if signatures and IS_WINDOWS:
        from .malware import check_signatures
        paths = sorted({e.path for e in entries if e.path and os.path.isfile(e.path) and not e.sig_status})
        if log and paths:
            log(f"Verifying digital signatures of {len(paths)} files…")
        try:
            sigs = check_signatures(paths, cancel) if paths else {}
        except Cancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            sigs = {}
            if log:
                log(f"Could not verify signatures: {type(exc).__name__}: {exc}")
        for e in entries:
            if e.sig_status:
                continue
            if e.path and e.path in sigs:
                e.sig_status, e.signer = sigs[e.path]
                e.signer = _short_signer(e.signer)
            elif e.path and not os.path.exists(e.path):
                e.sig_status = "Missing"
    for e in entries:
        _flag(e)
    return entries


def _short_signer(subject: str) -> str:
    m = re.search(r"CN=\"?([^,\"]+)", subject or "")
    return m.group(1).strip() if m else (subject or "")


def is_microsoft(e: AutoEntry) -> bool:
    return e.sig_status == "Valid" and e.signer.lower().startswith("microsoft")


# --------------------------------------------------------------------------- enable / disable
def set_enabled(e: AutoEntry, enabled: bool) -> None:
    if not e.can_toggle:
        raise RuntimeError(f"'{e.name}' cannot be enabled or disabled from here.")
    if IS_WINDOWS:
        _win_set_enabled(e, enabled)
    else:
        _linux_set_enabled(e, enabled)
    e.enabled = enabled


def _win_set_enabled(e: AutoEntry, enabled: bool) -> None:
    import time
    import struct
    import winreg
    from .platform_utils import run_cmd as _run
    if e.category in ("Run key", "Startup folder"):
        hive = winreg.HKEY_CURRENT_USER if e.meta.get("hive") == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        if hive == winreg.HKEY_LOCAL_MACHINE and not is_admin():
            raise NeedsAdmin(f"Change startup entry '{e.name}'")
        sub = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" + "\\" + e.meta["approved"]
        value_name = e.meta.get("value", e.name)
        if enabled:
            data = b"\x02" + b"\x00" * 11
        else:
            filetime = int((time.time() + 11644473600) * 10_000_000)
            data = b"\x03\x00\x00\x00" + struct.pack("<Q", filetime)
        with winreg.CreateKeyEx(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, value_name, 0, winreg.REG_BINARY, data)
        return
    if not is_admin():
        raise NeedsAdmin(f"Change '{e.name}'")
    if e.category == "Service":
        rc, out = _run(["sc", "config", e.meta["service"], "start=", "auto" if enabled else "disabled"])
    elif e.category == "Scheduled task":
        verb = "Enable-ScheduledTask" if enabled else "Disable-ScheduledTask"
        tp, tn = e.meta["task_path"].replace("'", "''"), e.meta["task"].replace("'", "''")
        rc, out = _run(["powershell", "-NoProfile", "-Command", f"{verb} -TaskPath '{tp}' -TaskName '{tn}'"])
    else:
        raise RuntimeError("Unsupported entry type.")
    if rc != 0:
        raise RuntimeError(out.strip() or f"Command failed with exit code {rc}.")


def _linux_set_enabled(e: AutoEntry, enabled: bool) -> None:
    from .platform_utils import run_stream
    if e.category == "Autostart":
        user_dir = os.path.expanduser("~/.config/autostart")
        os.makedirs(user_dir, exist_ok=True)
        target = os.path.join(user_dir, e.meta["file"])
        source = target if os.path.exists(target) else os.path.join("/etc/xdg/autostart", e.meta["file"])
        with open(source, encoding="utf-8") as fh:
            lines = [l for l in fh.read().splitlines() if not l.startswith(("Hidden=", "X-GNOME-Autostart-enabled="))]
        idx = next((i for i, l in enumerate(lines) if l.strip() == "[Desktop Entry]"), 0)
        lines.insert(idx + 1, f"Hidden={'false' if enabled else 'true'}")
        lines.insert(idx + 2, f"X-GNOME-Autostart-enabled={'true' if enabled else 'false'}")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return
    if e.category == "Service":
        verb = "enable" if enabled else "disable"
        if e.meta.get("user"):
            cmd = ["systemctl", "--user", verb, e.meta["unit"]]
        else:
            cmd = ["systemctl", verb, e.meta["unit"]]
            if not is_admin():
                cmd = wrap_privileged([cmd])
        rc, out = run_stream(cmd)
        if rc != 0:
            raise RuntimeError(out.strip() or f"systemctl failed with exit code {rc}.")
        return
    raise RuntimeError("Unsupported entry type.")


# --------------------------------------------------------------------------- change tracking
SNAPSHOT_VERSION = 2


def _snapshot_path() -> str:
    return os.path.join(app_data_dir(), "autoruns_snapshot.json")


def diff_with_snapshot(entries: list[AutoEntry], update: bool = True) -> tuple[list[dict], list[dict], str]:
    """Compare with the previous scan. Returns (added, removed, previous_scan_time)."""
    import time
    try:
        with open(_snapshot_path(), encoding="utf-8") as fh:
            prev = json.load(fh)
    except (OSError, json.JSONDecodeError):
        prev = {}
    # Snapshots from before version 2 stored Linux service details that change at every boot; treat them as
    # outdated and start a fresh baseline instead of reporting every service as removed and added.
    prev_items = prev.get("items", {}) if prev.get("version", 1) >= SNAPSHOT_VERSION else {}
    current = {e.key: {"category": e.category, "name": e.name, "command": e.command, "location": e.location}
               for e in entries}
    added = [v for k, v in current.items() if k not in prev_items] if prev_items else []
    removed = [v for k, v in prev_items.items() if k not in current] if prev_items else []
    if update:
        with open(_snapshot_path(), "w", encoding="utf-8") as fh:
            json.dump({"version": SNAPSHOT_VERSION, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "items": current},
                      fh, ensure_ascii=False)
    return added, removed, prev.get("time", "")


def to_dict(e: AutoEntry) -> dict:
    d = asdict(e)
    d["risk"] = e.risk
    return d
