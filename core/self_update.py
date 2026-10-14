"""Updates for SysHealth itself, from the project's GitHub releases.

The user always decides: a check only reports a newer version and a short summary of what changed.
Nothing is downloaded or replaced until the user chooses "Update now".

Release layout expected on GitHub (the build scripts produce these files in dist/):
    tag            v2.3.0                       (must match core/version.py)
    release notes  the text shown as "What's new" (Markdown bullets work best)
    assets         SysHealth.exe, SysHealthCLI.exe          Windows
                   SysHealth, SysHealthCLI                  Linux
                   SHA256SUMS-windows.txt, SHA256SUMS-linux.txt   checksums used to verify downloads
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import settings
from .platform_utils import CREATE_NO_WINDOW, IS_WINDOWS, Cancelled, app_data_dir
from .version import VERSION

# GitHub repository that publishes SysHealth releases, as "owner/repository".
# Can also be set without editing code: SysHealthCLI config set update-repo owner/repository
DEFAULT_REPO = "swaidi/SysHealth"

API = "https://api.github.com/repos/{repo}/releases/latest"
CHECK_INTERVAL_HOURS = 24
LogFn = Optional[Callable[[str], None]]


class UpdateError(Exception):
    """A readable problem with checking or installing an update."""


@dataclass
class Asset:
    name: str
    url: str
    size: int


@dataclass
class Release:
    version: str
    tag: str
    title: str
    published: str
    notes: str
    page: str
    assets: list[Asset] = field(default_factory=list)

    @property
    def summary(self) -> list[str]:
        return summarize_notes(self.notes)

    def asset(self, name: str) -> Optional[Asset]:
        return next((a for a in self.assets if a.name.lower() == name.lower()), None)


# --------------------------------------------------------------------------- settings
def repo() -> str:
    return (settings.get("update_repo") or DEFAULT_REPO).strip().strip("/")


def check_at_startup() -> bool:
    return bool(settings.get("update_check_startup", True))


def skipped_version() -> str:
    return settings.get("update_skip_version", "") or ""


def can_self_install() -> bool:
    """Only the built program can replace itself; from source, the user downloads manually."""
    return bool(getattr(sys, "frozen", False))


def due_for_check() -> bool:
    last = settings.get("update_last_check", "")
    try:
        return dt.datetime.now() - dt.datetime.fromisoformat(last) > dt.timedelta(hours=CHECK_INTERVAL_HOURS)
    except (TypeError, ValueError):
        return True


# --------------------------------------------------------------------------- versions
def parse_version(text: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", (text or "").split("-")[0].split("+")[0])
    return tuple(int(n) for n in nums[:4]) or (0,)


def is_newer(candidate: str, current: str = VERSION) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


# --------------------------------------------------------------------------- release notes
def summarize_notes(body: str, max_lines: int = 10, width: int = 120) -> list[str]:
    """Turn Markdown release notes into a short list of plain lines for the update prompt."""
    text = re.sub(r"<!--.*?-->", "", body or "", flags=re.S)
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("```", "---", "***", "|")) or line.startswith("!["):
            continue
        line = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", line)              # images
        line = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", line)            # links -> text
        line = re.sub(r"(\*\*|__|`)", "", line)                         # bold / code markers
        if re.match(r"(?i)full changelog", line):
            continue
        line = re.sub(r"\s+by @[\w-]+ in https?://\S+$", "", line)    # GitHub's generated notes
        line = re.sub(r"\s+in https?://github\.com/\S+/pull/\d+$", "", line)
        heading = re.match(r"#{1,6}\s*(.+)", line)
        if heading:
            title = heading.group(1).strip().rstrip(":")
            if re.fullmatch(r"(?i)(what'?s (new|changed)|changes|changelog|release notes|syshealth.*)", title):
                continue  # the prompt already has its own "What's new" heading
            line = title + ":"
        else:
            line = re.sub(r"^([-*+]|\d+[.)])\s+(\[[ xX]\]\s*)?", "• ", line)
        if len(line) > width:
            line = line[: width - 1].rstrip() + "…"
        if line.strip("•: "):
            lines.append(line)
    if not lines:
        return ["No details were published for this version."]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["…and more. See the full release notes."]
    return lines


# --------------------------------------------------------------------------- network
def _request(url: str, timeout: float = 15):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": f"SysHealth/{VERSION}"})
    return urllib.request.urlopen(req, timeout=timeout)


def _get_json(url: str) -> dict:
    try:
        with _request(url) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise UpdateError("No published release was found for SysHealth yet.") from exc
        if exc.code in (403, 429):
            raise UpdateError("GitHub is limiting requests right now. Try again in an hour.") from exc
        raise UpdateError(f"GitHub returned an error ({exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError("Could not reach GitHub. Check the internet connection and try again.") from exc
    except json.JSONDecodeError as exc:
        raise UpdateError("GitHub returned an unexpected answer.") from exc


def latest_release() -> Release:
    name = repo()
    if not name or "/" not in name:
        raise UpdateError("The update source is not set. Set DEFAULT_REPO in core/self_update.py, or run: "
                          "SysHealthCLI config set update-repo owner/repository")
    data = _get_json(API.format(repo=name))
    tag = data.get("tag_name") or ""
    return Release(
        version=tag.lstrip("vV"), tag=tag, title=data.get("name") or tag,
        published=(data.get("published_at") or "")[:10], notes=data.get("body") or "",
        page=data.get("html_url") or f"https://github.com/{name}/releases/latest",
        assets=[Asset(a.get("name", ""), a.get("browser_download_url", ""), int(a.get("size") or 0))
                for a in data.get("assets", [])])


def check(current: str = VERSION) -> Optional[Release]:
    """Return the latest release when it is newer than the running version, otherwise None."""
    release = latest_release()
    settings.set_value("update_last_check", dt.datetime.now().isoformat(timespec="seconds"))
    return release if is_newer(release.version, current) else None


# --------------------------------------------------------------------------- install
def _targets() -> list[tuple[str, str]]:
    """(asset name, local file) pairs to replace: the running program and the command-line tool beside it."""
    exe = os.path.abspath(sys.executable)
    folder = os.path.dirname(exe)
    gui, cli = ("SysHealth.exe", "SysHealthCLI.exe") if IS_WINDOWS else ("SysHealth", "SysHealthCLI")
    pairs = [(gui, exe)]
    if os.path.isfile(os.path.join(folder, cli)):
        pairs.append((cli, os.path.join(folder, cli)))
    return pairs


def download_size(release: Release) -> int:
    names = [name for name, _ in _targets()] if can_self_install() else []
    return sum(a.size for a in release.assets if a.name in names)


def _checksums(release: Release) -> dict[str, str]:
    sums: dict[str, str] = {}
    for a in release.assets:
        if not a.name.upper().startswith("SHA256SUMS"):
            continue
        with _request(a.url, timeout=30) as resp:
            for line in resp.read().decode("utf-8", "replace").splitlines():
                m = re.match(r"\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$", line)
                if m:
                    sums[os.path.basename(m.group(2))] = m.group(1).lower()
    return sums


def _writable(folder: str) -> bool:
    probe = os.path.join(folder, ".syshealth-write-test")
    try:
        with open(probe, "w"):
            pass
        os.remove(probe)
        return True
    except OSError:
        return False


def download(release: Release, log: LogFn = None, cancel: Optional[threading.Event] = None) -> list[tuple[str, str]]:
    """Download and verify the new files. Returns (downloaded file, file to replace) pairs."""
    if not can_self_install():
        raise UpdateError("Running from source: download the new version from the release page.")
    targets = _targets()
    folder = os.path.dirname(targets[0][1])
    if not _writable(folder):
        raise UpdateError(f"SysHealth cannot write to {folder}. Restart it as Administrator, "
                          "or download the new version from the release page.")
    missing = [name for name, _ in targets if not release.asset(name)]
    if missing:
        raise UpdateError(f"This release does not include {', '.join(missing)} for your system.")
    try:
        sums = _checksums(release)
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError("Could not download the checksum file to verify the update.") from exc

    stage = app_data_dir("updates", release.version)
    staged: list[tuple[str, str]] = []
    for name, target in targets:
        asset = release.asset(name)
        dest = os.path.join(stage, name)
        if log:
            log(f"Downloading {name} ({asset.size / 1_048_576:.1f} MB)…")
        digest = hashlib.sha256()
        done, next_report = 0, 0.25
        try:
            with _request(asset.url, timeout=60) as resp, open(dest + ".part", "wb") as fh:
                while True:
                    if cancel is not None and cancel.is_set():
                        raise Cancelled()
                    chunk = resp.read(256 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
                    digest.update(chunk)
                    done += len(chunk)
                    if log and asset.size and done / asset.size >= next_report:
                        log(f"  {int(done * 100 / asset.size)}%")
                        next_report += 0.25
        except (urllib.error.URLError, OSError) as exc:
            raise UpdateError(f"The download of {name} failed. Try again later.") from exc
        expected = sums.get(name)
        if expected and digest.hexdigest() != expected:
            os.remove(dest + ".part")
            raise UpdateError(f"{name} failed verification (checksum mismatch). The update was not installed.")
        if log:
            log(f"  {name}: " + ("checksum verified." if expected else "no checksum published; not verified."))
        os.replace(dest + ".part", dest)
        if not IS_WINDOWS:
            os.chmod(dest, 0o755)
        staged.append((dest, target))
    return staged


def apply(staged: list[tuple[str, str]], old_version: str, new_version: str) -> None:
    """Replace the program files and start the new version. The caller closes the app straight after."""
    settings.set_value("update_from", old_version)
    settings.set_value("update_to", new_version)
    exe = os.path.abspath(sys.executable)
    if IS_WINDOWS:
        _apply_windows(staged, exe)
    else:
        for new, target in staged:
            os.replace(new, target)  # Linux allows replacing a running program file
        subprocess.Popen([exe], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _apply_windows(staged: list[tuple[str, str]], exe: str) -> None:
    """A running .exe cannot be overwritten, so a small hidden script swaps the files after SysHealth closes."""
    import psutil
    pids = [os.getpid()]
    try:  # the one-file build runs as two processes; wait for the launcher too
        parent = psutil.Process().parent()
        if parent and os.path.normcase(parent.exe()) == os.path.normcase(exe):
            pids.append(parent.pid)
    except (psutil.Error, OSError):
        pass

    def q(s: str) -> str:
        return "'" + s.replace("'", "''") + "'"
    pairs = ",".join(f"@({q(n)},{q(t)})" for n, t in staged)
    logfile = os.path.join(app_data_dir("updates"), "update.log")
    script = f"""
$ErrorActionPreference = "Stop"
$log = {q(logfile)}
function Log($m) {{ Add-Content -ErrorAction SilentlyContinue -Path $log -Value ("[" + (Get-Date -Format s) + "] " + $m) }}
Log "Waiting for SysHealth to close"
Wait-Process -Id {",".join(map(str, pids))} -Timeout 60 -ErrorAction SilentlyContinue
foreach ($p in @({pairs})) {{
    $new = $p[0]; $target = $p[1]; $backup = $target + ".old"; $done = $false
    for ($i = 0; $i -lt 40 -and -not $done; $i++) {{
        try {{
            if (Test-Path -LiteralPath $backup) {{ Remove-Item -LiteralPath $backup -Force }}
            if (Test-Path -LiteralPath $target) {{ Move-Item -LiteralPath $target -Destination $backup -Force }}
            try {{ Move-Item -LiteralPath $new -Destination $target -Force; $done = $true; Log "Replaced $target" }}
            catch {{ if (Test-Path -LiteralPath $backup) {{ Move-Item -LiteralPath $backup -Destination $target -Force }}; throw }}
        }} catch {{ Start-Sleep -Milliseconds 500 }}
    }}
    if (-not $done) {{ Log "Could not replace $target; the previous version was kept" }}
}}
Start-Process -FilePath {q(exe)} -WorkingDirectory {q(os.path.dirname(exe))}
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"""
    path = os.path.join(app_data_dir("updates"), "apply_update.ps1")
    with open(path, "w", encoding="utf-8-sig") as fh:
        fh.write(script)
    subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                      "-WindowStyle", "Hidden", "-File", path],
                     creationflags=CREATE_NO_WINDOW | 0x00000008,  # DETACHED_PROCESS
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)


def finish_pending(current: str = VERSION) -> Optional[str]:
    """Called at startup: report the result of an update and remove leftovers. Returns a message or None."""
    target, previous = settings.get("update_to"), settings.get("update_from")
    if getattr(sys, "frozen", False):
        folder = os.path.dirname(os.path.abspath(sys.executable))
        for name in os.listdir(folder):
            if name.lower().endswith(".old") and name.lower().startswith("syshealth"):
                try:
                    os.remove(os.path.join(folder, name))
                except OSError:
                    pass
    if not target:
        return None
    settings.set_value("update_to", "")
    settings.set_value("update_from", "")
    if parse_version(target) == parse_version(current):
        return f"SysHealth was updated from {previous} to {current}."
    return f"The update to {target} did not complete; SysHealth {current} is still installed."
