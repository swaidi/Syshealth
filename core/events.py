"""Event log summary: groups recent errors and explains the common ones in plain language."""
from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field

from .platform_utils import IS_WINDOWS, ps_json, run_cmd

# (provider substring, event id) -> (severity, explanation, advice)
KNOWN_WINDOWS = {
    ("Kernel-Power", 41): ("High", "The computer restarted without shutting down cleanly (power loss, crash or "
                           "forced power-off).", "If frequent, check the power supply, overheating and drivers."),
    ("EventLog", 6008): ("Medium", "The previous shutdown was unexpected.", "Usually follows a crash or power loss."),
    ("BugCheck", 1001): ("High", "Windows crashed with a blue screen.", "Update drivers and run Disk Health and "
                         "'Repair system files'."),
    ("WER-SystemErrorReporting", 1001): ("High", "Windows crashed with a blue screen.", "Update drivers and run "
                                         "'Repair system files'."),
    ("Disk", 7): ("High", "The disk reported a bad block.", "Back up now and run Disk Health checks."),
    ("Disk", 51): ("High", "A disk error occurred while writing to the page file.", "Back up and check the disk."),
    ("Disk", 153): ("Medium", "A disk operation had to be retried.", "Check cables (desktop) or disk health."),
    ("Ntfs", 55): ("High", "File system corruption was detected.", "Run 'Full repair' for the affected drive."),
    ("Ntfs", 98): ("Medium", "A volume needs a file system check.", "Run 'Check drive' in Disk Health."),
    ("storahci", 129): ("Medium", "The storage controller was reset.", "Update storage drivers and firmware."),
    ("stornvme", 129): ("Medium", "The NVMe drive was reset.", "Update SSD firmware and storage drivers."),
    ("Application Error", 1000): ("Medium", "An application crashed.", "Update or reinstall the application named "
                                  "in the message."),
    ("Application Hang", 1002): ("Low", "An application stopped responding.", "Update the application if it recurs."),
    ("Service Control Manager", 7000): ("Medium", "A service failed to start.", "Check whether the related program "
                                        "is still installed."),
    ("Service Control Manager", 7031): ("Medium", "A service stopped unexpectedly.", "Update the related program."),
    ("Service Control Manager", 7034): ("Medium", "A service stopped unexpectedly.", "Update the related program."),
    ("Service Control Manager", 7023): ("Low", "A service ended with an error.", "Usually harmless if not repeated."),
    ("DistributedCOM", 10016): ("Info", "A harmless permission warning logged by Windows components.",
                                "No action needed."),
    ("DistributedCOM", 10010): ("Low", "A background component did not register in time.", "Usually harmless."),
    ("Kernel-PnP", 219): ("Low", "A driver failed to load for a device.", "Update the device driver."),
    ("Display", 4101): ("Medium", "The display driver stopped responding and recovered.", "Update the graphics driver."),
    ("WHEA-Logger", 17): ("Medium", "A hardware error was corrected automatically.", "Usually PCIe power saving; "
                          "update chipset drivers if frequent."),
    ("WHEA-Logger", 18): ("High", "A fatal hardware error occurred.", "Check CPU temperature, RAM and BIOS updates."),
    ("WHEA-Logger", 19): ("Medium", "A corrected hardware error occurred.", "Update BIOS and chipset drivers."),
    ("DNS Client Events", 1014): ("Low", "A DNS lookup timed out.", "Try the DNS & Speed page if browsing is slow."),
    ("Kernel-Boot", 29): ("Medium", "Windows failed to load a boot driver.", "Run 'Repair system files'."),
    ("volmgr", 161): ("Medium", "A crash dump could not be written.", "Check page file and free disk space."),
}
LINUX_PATTERNS = [
    (r"I/O error|blk_update_request|Buffer I/O", "High", "Disk read/write errors.", "Back up and run a SMART report."),
    (r"Out of memory|oom-kill|invoked oom-killer", "High", "The system ran out of memory and closed a program.",
     "Close heavy programs or add swap/RAM."),
    (r"segfault", "Medium", "A program crashed (segmentation fault).", "Update the program named in the message."),
    (r"EXT4-fs error|BTRFS error|XFS .*corruption", "High", "File system errors were detected.",
     "Repair the file system from a live USB (fsck)."),
    (r"Failed to start", "Medium", "A system service failed to start.", "Check the service with 'systemctl status'."),
    (r"ACPI (BIOS )?Error|ACPI Error", "Info", "Firmware (ACPI) table warnings, usually harmless.", "No action needed."),
    (r"firmware|microcode", "Low", "Firmware or microcode message.", "Install firmware updates (fwupd)."),
]
SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3, "Info": 4}


@dataclass
class EventGroup:
    source: str
    event_id: str
    count: int
    last: str
    first: str
    message: str
    severity: str = "Unknown"
    explanation: str = ""
    advice: str = ""
    samples: list[str] = field(default_factory=list)


def _explain_windows(provider: str, eid: int) -> tuple[str, str, str]:
    for (prov, i), info in KNOWN_WINDOWS.items():
        if i == eid and prov.lower() in provider.lower():
            return info
    return "Unknown", "", ""


def summarize(days: int = 7) -> list[EventGroup]:
    groups: dict[tuple, EventGroup] = {}
    if IS_WINDOWS:
        script = (f"$s=(Get-Date).AddDays(-{int(days)}); Get-WinEvent -FilterHashtable @{{LogName=@('System',"
                  "'Application'); Level=@(1,2); StartTime=$s}} -MaxEvents 4000 -ErrorAction SilentlyContinue | "
                  "ForEach-Object { [pscustomobject]@{T=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Id=$_.Id; "
                  "P=$_.ProviderName; M=if ($_.Message) { (($_.Message -split \"`n\")[0]).Trim() } else { '' } } }")
        for r in ps_json(script, timeout=240):
            prov, eid = r.get("P") or "?", int(r.get("Id") or 0)
            key = (prov, eid)
            g = groups.get(key)
            if g is None:
                sev, exp, adv = _explain_windows(prov, eid)
                g = groups[key] = EventGroup(prov, str(eid), 0, r.get("T", ""), r.get("T", ""), r.get("M", ""),
                                             sev, exp, adv)
            g.count += 1
            g.first = min(g.first, r.get("T", "")) if g.first else r.get("T", "")
            g.last = max(g.last, r.get("T", ""))
            if len(g.samples) < 3 and r.get("M") and r.get("M") not in g.samples:
                g.samples.append(r.get("M"))
    elif shutil.which("journalctl"):
        rc, out = run_cmd(["journalctl", "-p", "3", "--since", f"{int(days)} days ago", "-o", "json", "--no-pager"],
                          timeout=240)
        for line in out.splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = e.get("MESSAGE")
            if isinstance(msg, list):  # binary messages are returned as byte arrays
                msg = bytes(msg).decode("utf-8", "replace")
            msg = (msg or "").strip()
            src = e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or e.get("_SYSTEMD_UNIT") or "kernel"
            norm_msg = re.sub(r"\d+", "#", msg)[:90]
            try:
                import datetime as dt
                t = dt.datetime.fromtimestamp(int(e.get("__REALTIME_TIMESTAMP", "0")) / 1e6).strftime("%Y-%m-%d %H:%M")
            except (ValueError, OSError):
                t = ""
            key = (src, norm_msg)
            g = groups.get(key)
            if g is None:
                sev, exp, adv = "Unknown", "", ""
                for pat, s, x, a in LINUX_PATTERNS:
                    if re.search(pat, msg, re.I):
                        sev, exp, adv = s, x, a
                        break
                g = groups[key] = EventGroup(src, "", 0, t, t, msg[:300], sev, exp, adv)
            g.count += 1
            g.last = max(g.last, t)
            g.first = min(g.first, t) if g.first else t
    return sorted(groups.values(), key=lambda g: (SEV_ORDER.get(g.severity, 3), -g.count))


def headline(groups: list[EventGroup]) -> tuple[str, str, str]:
    high = [g for g in groups if g.severity == "High"]
    med = [g for g in groups if g.severity == "Medium"]
    if high:
        return "FAIL", f"{sum(g.count for g in high)} serious event(s)", high[0].explanation
    if med:
        return "WARN", f"{sum(g.count for g in med)} event(s) to review", med[0].explanation
    return "OK", "No serious errors", f"{sum(g.count for g in groups)} minor entries."
